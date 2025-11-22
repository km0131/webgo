package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"encoding/base64"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"golang.org/x/crypto/argon2"
)

const sessionKey = "signup_image_list"

func main() {
	db, err := sql.Open("sqlite3", "./web.sqlite3") //データベースを開く
	if err != nil {
		log.Fatal("sql.Openでエラー:", err)
	}
	defer db.Close() //データベースを閉じる
	err = db.Ping()
	if err != nil {
		log.Fatal("db.Pingでエラー:", err)
	}

	fmt.Println("SQLite DBに接続しました")

	r := gin.Default()
	secret := []byte("your-very-secret-key-that-should-be-long-and-random") // 秘密鍵 (シークレットキー) を設定します。
	store := cookie.NewStore(secret)                                        // 1. クッキーストアを作成
	r.Use(sessions.Sessions("mysession", store))                            // 2. セッションミドルウェアをルーターに適用
	rand.Seed(time.Now().UnixNano())

	r.LoadHTMLGlob("frontend/*.html")
	r.Static("/static", "./image")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ログイン画面",
		})
	})
	r.GET("/signup", func(c *gin.Context) {
		list, name, number, err := Random_image(db) //ランダムに画像のパスを取得
		if err != nil {
			log.Fatal("画像リストの生成中にエラーが発生しました:", err)
		}
		fmt.Println(list)
		fmt.Println(name)
		fmt.Println(number)
		// セッションを取得
		session := sessions.Default(c)
		// データを保存
		session.Set(sessionKey, number)
		// 変更を保存 (これがクッキーとしてクライアントに送信されます)
		session.Save()
		c.HTML(http.StatusOK, "signup.html", gin.H{
			"title":    "新規登録画面",
			"img":      list,
			"img_name": name,
		})
	})
	r.POST("/signup", func(c *gin.Context) { //フォームをDBに保存
		session := sessions.Default(c)
		// セッションからデータを取り出し
		number := session.Get(sessionKey)
		username := c.PostForm("inputUsername")
		email := c.PostForm("email")
		teacher := true
		password := c.PostFormArray("selected_images[]")
		if email == "" {
			email = "null"
			teacher = false
		}

		if err != nil {
			// ログ出力や、ユーザーへのエラーメッセージ表示
			log.Println(err)
		}
		count := 3
		password_1 := ""
		for i := 0; i < count; i++ {
			password_1 += password[i]
		}
		hashPassword_1, err := hashPassword(password_1, defaultParams) //ハッシュ化（Argon2）使用
		if err != nil {
			// エラー処理
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"message":      "ユーザー登録リクエストを受信しました",
			"user":         username,
			"email":        email,
			"teacher":      teacher,
			"password":     password,
			"password_1":   password_1,
			"number":       number,
			"hashPassword": hashPassword_1,
		})
	})
	r.Run(":8080")
}

// ハッシュ化
// パラメータ構造体: Argon2のコストパラメータを定義
type params struct {
	memory      uint32 // メモリコスト (KiB)
	iterations  uint32 // 反復回数 (タイムコスト)
	parallelism uint8  // 並列度 (スレッド数)
	saltLength  uint32 // ソルトの長さ
	keyLength   uint32 // 最終的なハッシュの長さ
}

// 推奨されるデフォルトパラメータ
var defaultParams = &params{
	memory:      128 * 1024, // 128MB (維持: セキュリティと8GBメモリを考慮)
	iterations:  2,          // 4から2に削減: 時間コストを半減
	parallelism: 2,          // 2スレッドに設定 (CPU占有抑制)
	saltLength:  16,         //ソイルの長さ
	keyLength:   32,         //最終的なハッシュの長さ
}

// hashPassword: パスワードをArgon2でハッシュ化し、Base64でエンコードされた文字列を返す
func hashPassword(password string, p *params) (hash string, err error) {
	// 1. セキュリティのためのソルトを生成
	salt := make([]byte, p.saltLength)
	_, err = rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("ソルトの生成に失敗: %w", err)
	}

	// 2. Argon2によるハッシュ計算
	hashBytes := argon2.IDKey(
		[]byte(password),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keyLength,
	)

	// 3. ハッシュ、ソルト、パラメータをまとめて文字列としてエンコード（データベース保存用）
	// 形式: $argon2id$v=19$m={memory},t={iterations},p={parallelism}${salt_base64}${hash_base64}
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hashBytes)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.memory,
		p.iterations,
		p.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// ユーザ登録DB
func InsertUser(db *sql.DB, name string, hashStr string, number string, email string, teacher bool) error {
	query := `INSERT INTO user (name,password,password_group, email,teacher) VALUES (?, ?, ?, ?, ?)`
	result, err := db.Exec(query, name, hashStr, number, email, teacher)
	if err != nil {
		return fmt.Errorf("データの挿入に失敗しました: %w", err)
	}

	// 挿入された行のIDを取得
	id, err := result.LastInsertId()
	if err == nil {
		log.Printf("登録成功！ユーザーID: %d\n", id)
	}

	// 影響を受けた行数を取得
	rowsAffected, _ := result.RowsAffected()
	log.Printf("影響を受けた行数: %d\n", rowsAffected)

	return nil
}

// ランダムに画像を選択
func Random_image(db *sql.DB) ([]string, []string, []int, error) {
	const totalCount = 30
	candidates := make([]int, totalCount)
	for i := 0; i < totalCount; i++ {
		candidates[i] = i + 1
	} //１から３０までのリストを作成
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}) //リストをランダムに並び替える
	number := candidates[:10]
	list, name, err := Image_DB(db, number)
	if err != nil {
		log.Fatal("画像リストのDB検索でエラーが出ました。:", err)
	}
	return list, name, number, nil
}

// 画像番号からリンクとDB検索を行う
func Image_DB(db *sql.DB, number []int) ([]string, []string, error) {
	const selectionCount = 10
	list := make([]string, 0, selectionCount)
	name := make([]string, 0, selectionCount)
	for i := 0; i < selectionCount; i++ {
		imageID := number[i]
		r := "static/certification/" + strconv.Itoa(imageID) + ".png"
		var fetchedName string
		query := `SELECT name FROM certification WHERE id = ?`
		err := db.QueryRow(query, imageID).Scan(&fetchedName)
		if err != nil {
			// 取得エラーが発生した場合、エラーを返し、スライスはnilにする
			return nil, nil, fmt.Errorf("ID %d のデータ取得に失敗しました: %w", imageID, err)
		}
		list = append(list, r)
		name = append(name, fetchedName)
	}
	return list, name, nil
}

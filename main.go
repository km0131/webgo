package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"

	"encoding/base64"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"golang.org/x/crypto/argon2"

	"github.com/google/uuid"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"
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
	rand.Seed(time.Now().UnixNano())                                        //乱数の生成を初期化

	r.LoadHTMLGlob("frontend/*.html") //HTMLの場所を指定
	r.Static("/static", "./image")    //画像の場所を指定
	r.GET("/", func(c *gin.Context) { //一番最初のログイン画面
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ログイン画面",
		})
	})
	r.GET("/signup", func(c *gin.Context) { //アカウント作成
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
		session.Set(sessionKey, number) //表示された画像の番号をセッションに保存
		// 変更を保存 (これがクッキーとしてクライアントに送信されます)
		session.Save()
		c.HTML(http.StatusOK, "signup.html", gin.H{ //画像のリンクと名前をＨＴＭＬに送信し画面を構築
			"title":    "新規登録画面",
			"img":      list,
			"img_name": name,
		})
	})
	r.POST("/signup", func(c *gin.Context) { //フォームをDBに保存
		session := sessions.Default(c)
		// セッションからデータを取り出し
		number := session.Get(sessionKey)
		// セッションの値nil チェック
		if number == nil {
			log.Println("セッションキーが見つかりません。シリアライズをスキップします。")
			return
		}
		intnumber, ok := number.([]int) //セッションの値をスライスに変換
		if !ok {
			// 型が期待した []int ではない場合の処理
			log.Printf("ユーザー番号の型が期待通りではありません: 実際の型 %T", intnumber)
			return
		}
		num := serializeIntSlice(intnumber)              //DBに保存する為にスライスを文字列に変更
		username := c.PostForm("inputUsername")          //ユーザー名
		email := c.PostForm("email")                     //メールアドレス
		teacher := true                                  //生徒か先生か？初期値は先生
		password := c.PostFormArray("selected_images[]") //パスワードとして選択した画像の名前を取得
		if email == "" {                                 //メールアドレスが空の場合は生徒なので生徒に変更
			email = "null"  //DB保存の為NULLを設定
			teacher = false //生徒に変更
		}
		count := 3
		password_1 := ""             //DBに保存する文字列の関数
		for i := 0; i < count; i++ { //値を取り出して文字列として保存
			password_1 += password[i]
		}
		hashPassword_1, err := hashPassword(password_1, defaultParams) //文字列に変換したパスワードをハッシュ化（Argon2）使用
		if err != nil {
			// エラー処理
			log.Fatal(err)
		}
		DB_name, err := InsertUser(db, username, hashPassword_1, num, email, teacher) //DBに保存
		if err != nil {
			// エラー処理
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, gin.H{
			"message":      "ユーザー登録リクエストを受信しました",
			"user":         DB_name,
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

// ユーザー登録DB
func InsertUser(db *sql.DB, name string, hashStr string, number string, email string, teacher bool) (DB_name string, err error) {
	const maxRetries = 3
	newID := uuid.New().String()
	for i := 0; i < maxRetries; i++ {
		// ユーザー名 を生成
		name_uuid, err := createUniqueUsername(name)
		// 【修正点】: デバッグログとして記録し、パニックを避ける
		log.Printf("生成されたユーザー名: %s", name_uuid)
		if err != nil {
			log.Printf("ユーザー名サフィックス生成エラー: %v", err)
			return "", err
		}
		query := `INSERT INTO user (id, name, password, password_group, email, teacher) VALUES (?, ?, ?, ?, ?, ?)`
		result, err := db.Exec(query, newID, name_uuid, hashStr, number, email, teacher)
		if err == nil {
			log.Printf("ユーザー登録成功。試行回数: %d, ユーザー名: %s", i+1, name_uuid)
			// UUIDを使用しているため LastInsertId は不要
			rowsAffected, _ := result.RowsAffected()
			log.Printf("影響を受けた行数: %d\n", rowsAffected)
			return name_uuid, nil
		}
		// UNIQUE制約違反であるかを確認
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint && strings.Contains(sqliteErr.Error(), "UNIQUE constraint failed") {
			log.Printf("UNIQUE制約違反が発生しました (試行回数: %d)。サフィックスを変えて再試行します。", i+1)
			continue // ループ継続
		} else {
			log.Printf("データベース挿入中に予期せぬエラーが発生しました: %v", err)
			return "", fmt.Errorf("データベース挿入エラー: %w", err)
		}
	}
	return "", fmt.Errorf("ユーザー名の生成と挿入に%d回失敗しました。この名前では登録できません。", maxRetries)
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
	list, name, err := Image_DB(db, number) //画像リンクと名前を取得
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
		r := "static/certification/" + strconv.Itoa(imageID) + ".png" //画像絵リンクの作成
		var fetchedName string
		query := `SELECT name FROM certification WHERE id = ?` //DBから画像の名前を取得
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

// 文字を結合[1,2,3] => "1,2,3"(DB保存の為)
func serializeIntSlice(slice []int) string {
	strSlice := make([]string, len(slice))
	//各要素を文字列に変換
	for i, num := range slice {
		strSlice[i] = strconv.Itoa(num)
	}
	//カンマで結合
	return strings.Join(strSlice, ",")
}

// 名前の一意性を保つために4桁のUUIDを生成し追加
func createUniqueUsername(desiredName string) (string, error) {
	// ユーザー名の長さ制限に合わせて、希望の名前を正規化/短縮する
	normalizedName, err := normalizeJapaneseUsername(desiredName)
	if err != nil {
		log.Panicln("正規化でエラー%w", err)
	}
	// ４文字のランダムなサフィックスを生成
	suffix, err := generateRandomSuffix(4)
	if err != nil {
		return "", err
	}
	// 結合して最終的なユーザー名を生成 (例: tanaka-h7v8xPzM)
	finalUsername := fmt.Sprintf("%s-%s", normalizedName, suffix)
	// DBのUNIQUE制約と競合した場合は、呼び出し元でこの関数を再試行するロジックが必要
	return finalUsername, nil
}

// 一意性を保つための複合正規化処理
func normalizeJapaneseUsername(desiredName string) (string, error) {
	// 濁音とかを処理して半角に
	t := transform.Chain(norm.NFKC, width.Fold)
	output, _, err := transform.String(t, desiredName)
	if err != nil {
		return "", err
	}
	// 英字部分を小文字に統一する
	normalizedName := strings.ToLower(output)
	// 空白や制御文字の除去 (必要に応じて)
	normalizedName = strings.TrimSpace(normalizedName)
	return normalizedName, nil
}

// UUIDの生成名前用
func generateRandomSuffix(length int) (string, error) {
	// ターゲット長に合わせて、必要なランダムバイト数を決定
	// Base64は通常、3バイトを4文字に変換するため、必要なバイト数を計算する
	byteLength := (length * 3) / 4
	randomBytes := make([]byte, byteLength)
	//crypto/rand で安全な乱数バイトを生成
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("乱数生成エラー: %w", err)
	}
	// Base64 (RawURLEncoding) でエンコードし、特殊文字を排除
	// RawURLEncoding は +, /, = を含まないため、URLやユーザー名に安全
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)
	// 指定された長さで切り取り、返却
	// 指定長より短くなる可能性があるため、Min関数で安全に切り取る
	if len(encoded) > length {
		return encoded[:length], nil
	}
	// 十分な長さが得られなかった場合もそのまま返す（安全性を優先）
	return encoded, nil
}

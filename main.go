package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"database/sql"
	"fmt"
	"log"

	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

func main() {
	db, err := sql.Open("sqlite3", "./web.sqlite3")
	if err != nil {
		log.Fatal("sql.Openでエラー:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("db.Pingでエラー:", err)
	}

	fmt.Println("SQLite DBに接続しました")

	r := gin.Default()
	r.LoadHTMLGlob("frontend/*.html")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ログイン画面",
		})
	})
	r.GET("/signup", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signup.html", gin.H{
			"title": "新規登録画面",
		})
	})
	r.POST("/signup", func(c *gin.Context) { //フォームをDBに保存
		salt := make([]byte, 16) // ランダムSalt生成
		if _, err := rand.Read(salt); err != nil {
			fmt.Println("saltでエラー：", err)
		}
		username := c.PostForm("inputUsername")
		password := c.PostForm("password")
		email := c.PostForm("email")
		teacher := true
		if email == "" {
			email = "null"
			teacher = false
		}

		//ハッシュ化
		hashStr := hashing(password, string(salt))

		// Base64に変換して保存可能に
		saltStr := base64.RawStdEncoding.EncodeToString(salt)

		err := InsertUser(db, username, hashStr, saltStr, email, teacher)

		if err != nil {
			// ログ出力や、ユーザーへのエラーメッセージ表示
			log.Println(err)
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "ユーザー登録リクエストを受信しました",
			"user":    username,
			"pass":    hashStr,
			"salt":    saltStr,
			"email":   email,
			"teacher": teacher,
		})
	})
	r.Run(":8080")
}

// ハッシュ化関数
func hashing(password string, salt string) string {
	// まずSHA-512で一次ハッシュ
	shaHash := sha512.Sum512([]byte(password))
	// 軽量Argon2idパラメータ
	const time = 1           //（反復回数）
	const memory = 32 * 1024 // （使用メモリ）32 MB
	const threads = 1        //（並列度
	const keyLen = 32        //（ハッシュ長）：

	// SHA-512ハッシュにSaltを付与してArgon2id(二次ハッシュ)
	argonHash := argon2.IDKey(shaHash[:], []byte(salt), time, memory, threads, keyLen)

	return base64.RawStdEncoding.EncodeToString(argonHash)
}

// ユーザ登録関数
func InsertUser(db *sql.DB, name string, hashStr string, saltStr string, email string, teacher bool) error {
	query := `INSERT INTO user (name,password,salt, email,teacher) VALUES (?, ?, ?, ?, ?)`
	result, err := db.Exec(query, name, hashStr, saltStr, email, teacher)
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

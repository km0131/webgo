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
)

func main() {
	rand.Seed(time.Now().UnixNano())
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
	r.Static("/static", "./image")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ログイン画面",
		})
	})
	r.GET("/signup", func(c *gin.Context) {
		list, name, err := Random_image(db) //ランダムに画像のパスを取得
		if err != nil {
			log.Fatal("画像リストの生成中にエラーが発生しました:", err)
		}
		fmt.Println(list)
		fmt.Println(name)
		c.HTML(http.StatusOK, "signup.html", gin.H{
			"title":    "新規登録画面",
			"img":      list,
			"img_name": name,
		})
	})
	r.POST("/signup", func(c *gin.Context) { //フォームをDBに保存
		username := c.PostForm("inputUsername")
		email := c.PostForm("email")
		teacher := true
		if email == "" {
			email = "null"
			teacher = false
		}

		if err != nil {
			// ログ出力や、ユーザーへのエラーメッセージ表示
			log.Println(err)
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "ユーザー登録リクエストを受信しました",
			"user":    username,
			"email":   email,
			"teacher": teacher,
		})
	})
	r.Run(":8080")
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

// ランダムに画像を選択
func Random_image(db *sql.DB) ([]string, []string, error) {
	const totalCount = 30
	candidates := make([]int, totalCount)
	for i := 0; i < totalCount; i++ {
		candidates[i] = i + 1
	} //１から３０までのリストを作成
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	}) //リストをランダムに並び替える
	const selectionCount = 10
	list := make([]string, 0, selectionCount)
	name := make([]string, 0, selectionCount)
	for i := 0; i < selectionCount; i++ {
		imageID := candidates[i]
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

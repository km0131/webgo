	r.LoadHTMLGlob("frontend/*.html") //HTMLの場所を指定
	r.Static("/static", "./image")    //画像の場所を指定
	r.GET("/", func(c *gin.Context) { //一番最初のログイン画面
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "ログイン画面",
		})
	})
	r.POST("/", func(c *gin.Context) {
		username := c.PostForm("inputUsername")
		var fetcheduser user
		result := db.Where("name = ?", username).Find(&fetcheduser)
		if result.Error != nil {
			// IDが無い
			log.Fatal("指定IDリストのデータ取得に失敗しました: %w", result.Error)
		}
		if result.RowsAffected == 0 { //ユーザが登録されていない。
			fmt.Println("指定されたユーザー名が見つかりませんでした。")
			c.HTML(http.StatusOK, "login.html", LoginPageData{
				ErrorMessage: "入力されたユーザー名は存在しません。再度確認してください。",
			})
			return
		}
		stringValues := strings.Split(fetcheduser.PasswordGroup, ",") //スライス型の為に”、”で分割
		var number []int
		for _, s := range stringValues { //画像番号のスライスを作成
			i, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				// エラー処理 (変換できない値が含まれていた場合)
				fmt.Printf("数値への変換に失敗: %v\n", err)
				continue
			}
			number = append(number, i)
		}
		fmt.Println("スライス化された値:", number)
		list, name, err := Image_DB(db, number) //画像リンクと名前を取得
		if err != nil {
			log.Fatal("画像リストのDB検索でエラーが出ました。:", err)
		}
		c.HTML(http.StatusOK, "login_p.html", gin.H{
			"img":      list,
			"img_name": name,
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

//暗号化
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// Encrypt は文字列を暗号化し、Base64形式で返します
func Encrypt(plaintext string) (string, error) {
	// 環境変数から32バイトの鍵を取得
	keyStr := os.Getenv("APP_MASTER_KEY")
	// opensslで生成したBase64形式をデコードして32バイトのバイナリにする
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid master key: must be 32 bytes (base64)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// ナンス（12バイト）をランダム生成
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 暗号化実行。ナンスを先頭にくっつけて返す（gcm.Sealの第1引数がプレフィックスになる）
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt はBase64形式の暗号文を元の文字列に戻します
func Decrypt(cryptoText string) (string, error) {
	keyStr := os.Getenv("APP_MASTER_KEY")
	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid master key")
	}

	data, err := base64.StdEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	// 先頭12バイト(ナンス)とそれ以降(暗号文)に分ける
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err // 改ざん検知機能。鍵が違うかデータが壊れているとここでエラーになる
	}

	return string(plaintext), nil
}

func main() {
	// 1. 暗号化テスト
	rawPass := "MyPiPassword2026"
	encrypted, err := Encrypt(rawPass)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Printf("暗号化済み (これをDBに保存): %s\n", encrypted)

	// 2. 復号テスト
	decrypted, err := Decrypt(encrypted)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Printf("復号結果 (これをQRに使用): %s\n", decrypted)
}
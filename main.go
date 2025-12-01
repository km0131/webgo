package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"encoding/base64"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"golang.org/x/crypto/argon2"

	"github.com/google/uuid"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"golang.org/x/text/width"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const sessionKey = "signup_image_list"

type user struct { //ユーザ登録のDB
	ID            string         `gorm:"type:VARCHAR(36) PRIMARY KEY"` // ID(UUID)を使用
	CreatedAt     time.Time      //作成日時
	UpdatedAt     time.Time      //更新日時
	DeletedAt     gorm.DeletedAt `gorm:"index"`                      //倫理削除
	Name          string         `gorm:"type:text;unique;not null"`  // TEXT UNIQUE NOT NULL 名前
	Password      string         `gorm:"type:varchar(255);not null"` // VARCHAR(255) NOT NULL パスワード
	PasswordGroup string         `gorm:"type:text;not null"`         // TEXT NOT NULL 画像のグループ
	Email         string         `gorm:"type:text"`                  // TEXT メール（生徒は登録しないためNULLを許容）
	Teacher       bool           `gorm:"type:boolean;not null"`      // BOOLEAN NOT NULL 生徒か生徒かを登録
}

type certification struct { //セキュリティー用画像のDB
	ID   uint   `gorm:"primaryKey"` //画像番号
	Name string `gorm:"not null"`   //画像の名前
}

// テンプレートに渡すデータ構造
type LoginPageData struct {
	ErrorMessage string // エラーメッセージ
}

func main() {
	//データベースに接続
	db, err := gorm.Open(sqlite.Open("web.sqlite3"), &gorm.Config{})
	if err != nil {
		log.Fatal("データベースへの接続に失敗しました:", err)
	}
	db.AutoMigrate(&user{}, certification{})
	fmt.Println("テーブル 'use', 'certification' のマイグレーションが完了しました。")

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
func InsertUser(db *gorm.DB, name string, hashStr string, number string, email string, teacher bool) (DB_name string, err error) {
	const maxRetries = 3
	newID := uuid.New().String()
	for i := 0; i < maxRetries; i++ {
		// ユーザー名 を生成
		name_uuid, err := createUniqueUsername(name)
		// デバッグログとして記録し、パニックを避ける
		log.Printf("生成されたユーザー名: %s", name_uuid)
		if err != nil {
			log.Printf("ユーザー名サフィックス生成エラー: %v", err)
			return "", err
		}
		newName := user{
			ID:            newID,
			Name:          name_uuid,
			Password:      hashStr,
			PasswordGroup: number,
			Email:         email,
			Teacher:       teacher,
		}
		result := db.Create(&newName)
		// 挿入後のエラーチェックを追加
		if result.Error != nil {
			// ログに出力し、処理を中断するか、エラーレスポンスを返す
			log.Printf("挿入試行 %d 回目失敗: %v", i+1, result.Error)
			continue
		}

		if result.RowsAffected > 0 {
			log.Printf("ユーザー名 %s で挿入に成功しました。", newName.Name)
			return newName.Name, nil // 成功したので、生成されたユーザー名を返して終了
		}

		// 影響を受けた行数が0でないかも確認できる
		if result.RowsAffected == 0 {
			log.Println("警告: 挿入された行数が0でした。")
		}
	}
	return "", fmt.Errorf("ユーザー名の生成と挿入に%d回失敗しました。この名前では登録できません。", maxRetries)
}

// ランダムに画像を選択
func Random_image(db *gorm.DB) ([]string, []string, []int, error) {
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
func Image_DB(db *gorm.DB, number []int) ([]string, []string, error) {
	var fetchedCertifications []certification
	result := db.Where("id IN ?", number).Find(&fetchedCertifications) //１回で全てのデータを取得
	if result.Error != nil {
		// IDが無い
		return nil, nil, fmt.Errorf("指定IDリストのデータ取得に失敗しました: %w", result.Error)
	}
	const selectionCount = 10
	list := make([]string, 0, selectionCount)
	name := make([]string, 0, selectionCount)
	for _, i := range fetchedCertifications {
		imageIDStr := strconv.Itoa(int(i.ID))
		r := "static/certification/" + imageIDStr + ".png" // 画像リンクの作成
		list = append(list, r)                             //画像のパスをリストに追加
		name = append(name, i.Name)                        // 画像の名前をリストに追加
	}
	// 取得した数が必要な数と異なるときのチェック
	if len(fetchedCertifications) != len(number) {
		// ランダムに選ばれたIDの一部が見つからなかった
		log.Printf("警告: 期待値 %d 件に対し、取得件数は %d 件でした。", len(number), len(fetchedCertifications))
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

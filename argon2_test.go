package main

import (
	"testing"
)

// パラメータ構造体はargon2.goから参照される前提
// var raspiOptimizedParams ... (設定したいパラメータ)
// func hashPassword(password string, p *params) (hash string, err error) { ... }

// Argon2のハッシュ計算速度を測定するベンチマーク関数
func BenchmarkArgon2Hash(b *testing.B) {
	// 測定に使用するダミーのパスワード
	password := "very_secure_password_for_testing"
	// 測定したいパラメータ設定 (例: 前回の推奨設定)
	// 注意: ここで定義する defaultParams は、argon2.go の構造体と一致している必要があります
	paramsToTest := &params{
		memory:      128 * 1024, // 128MB (維持: セキュリティと8GBメモリを考慮)
		iterations:  2,          // 4から2に削減: 時間コストを半減
		parallelism: 2,          // 2スレッドに設定 (CPU占有抑制)
		saltLength:  16,
		keyLength:   32,
	}

	// タイマーをリセットし、ループを開始
	b.ResetTimer()

	// b.N はテストフレームワークが実行する回数
	for i := 0; i < b.N; i++ {
		// hashPassword関数を呼び出し、ハッシュ化を実行
		_, err := hashPassword(password, paramsToTest)
		if err != nil {
			// エラーが発生したら、ベンチマークを停止
			b.Fatal(err)
		}
	}
}

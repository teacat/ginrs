# GinRS [![GoDoc](https://godoc.org/github.com/teacat/ginrs/?status.svg)](https://godoc.org/github.com/teacat/ginrs) [![Go Report Card](https://goreportcard.com/badge/github.com/teacat/ginrs)](https://goreportcard.com/report/github.com/teacat/ginrs)

套用在 [gin-gonic/gin](https://github.com/gin-gonic/gin) 基於 RS256 演算法的 JWT 簽署套件。

## 非對稱金鑰

透過 `openssl` 產生一個私鑰。

```go
openssl genrsa -out private.key 2048
```

再透過這個私鑰產生一個公鑰，這個公鑰可以配發到其他伺服器或是第三方的手中用來驗證未來的 JWT 是否都由同人所簽署。

```go
openssl rsa -in private.key -pubout > public.key
```

## 使用方式

產生金鑰，便能透過下列方式簽署 JWT，並以公鑰驗證其簽發正確性。

```go
import "github.com/teacat/ginrs"

type Data struct {
	Username string
}

func main() {
    // 欲簽署的資料。
	data := Data{
		Username: "YamiOdymel",
	}

	// 因為要簽署和驗證，所以必須載入公私鑰兩個檔案。
	err := ginrs.LoadKeys("./tests/public.key", "./tests/private.key")
	if err != nil {
		panic(err)
	}

	// 將資料透過 RS256 簽署成一個 JWT。
	token, err := ginrs.SignRS256(data)
	if err != nil {
		panic(err)
	}

	// 驗證這個 JWT 是否正確。
	var signedData Data
	err = ginrs.Parse(token, &signedData)
	if err != nil {
		panic(err)
	}

    fmt.Println(signedData.Username) // 輸出：YamiOdymel
}
```

若沒有要進行簽署，而只是要驗證 JWT 是否正確，則可以將 `LoadKeys` 替換成 `LoadPublicKey` 僅載入公鑰作為驗證用途而不需要私鑰。

### 用於 Gin 的中介函式

透過 `Middleware` 函式可以在每個請求進入時將 JWT 簽署的資料放入 `*gin.Context` 的變數中。

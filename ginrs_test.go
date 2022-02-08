package ginrs

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type Data struct {
	Username string
	Nickname string
}

type WrongData struct {
	Username string
	Nickname string
}

func (d Data) Valid() error {
	return nil
}

type GinRSSuite struct {
	suite.Suite

	signedRS256 string
}

func (s *GinRSSuite) SetupSuite() {

}

func TestGinRSSuite(t *testing.T) {
	suite.Run(t, new(GinRSSuite))
}

func (s *GinRSSuite) TestGinRSSuite() {
	s.Run("LoadKeys", s.LoadKeys)
	s.Run("SignRS256", s.SignRS256)
	s.Run("Parse", s.Parse)
	s.Run("ParseInvalid", s.ParseInvalid)
}

func (s *GinRSSuite) LoadKeys() {
	s.NoError(LoadKeys("./tests/public.key", "./tests/private.key"))
}

func (s *GinRSSuite) SignRS256() {
	t, err := SignRS256(Data{
		Username: "YamiOdymel",
		Nickname: "Xiaoan",
	})
	s.NoError(err)
	s.NotEmpty(t)
	s.signedRS256 = t
}

func (s *GinRSSuite) Parse() {
	var data Data
	s.NoError(Parse(s.signedRS256, &data))
	s.Equal("YamiOdymel", data.Username)
	s.Equal("Xiaoan", data.Nickname)
}

func (s *GinRSSuite) ParseInvalid() {
	s.NoError(LoadPublicKey("./tests/public_invalid.key"))
	var data Data
	s.Error(Parse(s.signedRS256, &data))
}

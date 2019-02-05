package client

type Client interface {
	CheckThreat(checkURL string) (bool, error)
}

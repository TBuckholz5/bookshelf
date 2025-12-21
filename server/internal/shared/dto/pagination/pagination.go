package pagination

type PaginatatableRequest interface {
	GetOffset() int
	GetLimit() int
	SetOffset(offset int)
	SetLimit(limit int)
}

type PaginationInfo struct {
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

type PaginatableResponse interface {
	GetCount() int
	GetHasMore() bool
	SetCount(count int)
	SetHasMore(hasMore bool)
}

type PaginationResponse[T any] struct {
	PaginationInfo
	Count   int  `json:"count"`
	HasMore bool `json:"hasMore"`
	Data    []T  `json:"data"`
}

func (p *PaginationInfo) GetOffset() int {
	return p.Offset
}

func (p *PaginationInfo) GetLimit() int {
	return p.Limit
}

func (p *PaginationInfo) SetOffset(offset int) {
	p.Offset = offset
}

func (p *PaginationInfo) SetLimit(limit int) {
	p.Limit = limit
}

func (p *PaginationResponse[T]) GetCount() int {
	return p.Count
}

func (p *PaginationResponse[T]) GetHasMore() bool {
	return p.HasMore
}

func (p *PaginationResponse[T]) SetCount(count int) {
	p.Count = count
}

func (p *PaginationResponse[T]) SetHasMore(hasMore bool) {
	p.HasMore = hasMore
}

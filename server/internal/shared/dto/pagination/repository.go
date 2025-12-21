package pagination

import "context"

type PaginatedRepository[T any, U PaginatatableRequest] interface {
	GetAll(ctx context.Context, params U) ([]T, error)
}

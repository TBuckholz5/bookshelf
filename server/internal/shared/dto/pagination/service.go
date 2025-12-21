package pagination

import "context"

func GetAll[T any, U PaginatatableRequest](ctx context.Context, repo PaginatedRepository[T, U], params U) (PaginationResponse[T], error) {
	params.SetLimit(params.GetLimit() + 1)
	items, err := repo.GetAll(ctx, params)
	if err != nil {
		return PaginationResponse[T]{}, err
	}

	repoCount := len(items)
	actualCount := max(repoCount-1, 0)
	response := PaginationResponse[T]{
		Count:   actualCount,
		HasMore: false,
		Data:    items[:actualCount],
		PaginationInfo: PaginationInfo{
			Offset: params.GetOffset(),
			Limit:  params.GetLimit() - 1,
		},
	}

	if len(items) > params.GetLimit()-1 {
		response.HasMore = true
		response.Count = params.GetLimit() - 1
	}

	return response, nil
}

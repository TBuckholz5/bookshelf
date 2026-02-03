package service

type serviceError struct {
	message string
}

// Represents unauthorized errors.
type UnauthorizedError struct {
	serviceError
}

func NewUnauthorizedError(msg string) *UnauthorizedError {
	return &UnauthorizedError{
		serviceError: serviceError{
			message: msg,
		},
	}
}

func (e *UnauthorizedError) Error() string {
	return e.message
}

// Represents internal errors.
type InternalError struct {
	serviceError
}

func NewInternalError(msg string) *InternalError {
	return &InternalError{
		serviceError: serviceError{
			message: msg,
		},
	}
}

func (e *InternalError) Error() string {
	return e.message
}

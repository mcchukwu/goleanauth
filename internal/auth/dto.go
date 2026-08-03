package auth

type RegisterRequest struct {
	Email string `json:"email" validate:"omitempty,email,max=100"`
	Phone string `json:"phone" validate:"omitempty,phone"`

	FirstName string `json:"first_name" validate:"omitempty,min=2,max=50"`
	LastName  string `json:"last_name" validate:"omitempty,min=2,max=50"`

	Password string `json:"password" validate:"required,min=8,max=72"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,identifier"`
	Password   string `json:"password" validate:"required,min=8,max=72"`
}

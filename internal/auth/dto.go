package auth

type RegisterRequest struct {
	Email string `json:"email" validate:"omitempty,email,max=100"`
	Phone string `json:"phone" validate:"omitempty,ngphone"`

	Password string `json:"password" validate:"required,min=8,max=72"`

	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,identifier"`
	Password   string `json:"password" validate:"required,min=4,max=72"`
}

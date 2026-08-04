package auth

type RegisterRequest struct {
	Email string `json:"email,omitempty" validate:"email,max=100"`
	Phone string `json:"phone,omitempty" validate:"phone,max=100"`

	FirstName string `json:"first_name" validate:"min=2,max=50"`
	LastName  string `json:"last_name" validate:"min=2,max=50"`

	Password string `json:"password" validate:"required,min=6,max=72"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" validate:"required,identifier"`
	Password   string `json:"password" validate:"required,min=8,max=72"`
}

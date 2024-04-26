package types

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email,min=6"`
	Password string `json:"password" validate:"required,min=6"`
}

type RegisterPayload struct {
	Email           string `json:"email" validate:"required,email,min=6"`
	Username        string `json:"username" validate:"required,min=4,max=32"`
	Password        string `json:"password" validate:"required,min=6"`
	ConfirmPassword string `json:"confirm_password" validate:"required,min=6,eqfield=Password"`
}

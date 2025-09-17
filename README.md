# goauth

![auth user model](user_model.png)


<!-- run teh migartions and apply them -->
go run ./cmd/migrate down

<!-- create migration files -->
migrate create -ext sql -dir cmd/migrate/migrations -seq tokenblacklist
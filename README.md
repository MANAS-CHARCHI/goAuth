FOR make migration files

migrate create -ext sql -dir ./cmd/migrate/migrations -seq create_users_table

migration up & down
manascharchi@Manass-MacBook-Air goAuth % go run ./cmd/migrate/main.go up
manascharchi@Manass-MacBook-Air goAuth % go run ./cmd/migrate/main.go down

<!-- AIR run -->

echo 'export PATH=$HOME/go/bin:$PATH' >> ~/.zshrc
source ~/.zshrc

<!-- remove swagger -->

rm -rf docs/docs.go docs/swagger.json docs/swagger.yaml

<!-- add swagger -->

swag init -g cmd/api/main.go

<!-- -->
# goauth
# goAuth

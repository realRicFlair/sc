package db

import (
	"context"
	"github.com/jackc/pgx/v5"
	"log"
)

func checkErr(err error) {
	if err != nil {
		log.Printf("DB Error: %v", err)
	}
}

var dbConnection *pgx.Conn

func ConnectDB() {
	//Connect to DB
	var err error
	dbConnection, err = pgx.Connect(context.Background(), "10.0.0.6")
	defer dbConnection.Close(context.Background())
	checkErr(err)
}

func QueryRow(sql string, args ...interface{}) pgx.Row {
	return dbConnection.QueryRow(context.Background(), sql, args...)
}

func addSessionToDB() {
	sql := "INSERT INTO sessions (session_token, user_id) VALUES ($1, $2)"

	dbConnection.QueryRow(context.Background(), sql, "123456", "1")
}

func getUserIDfromSession(sessionToken string) string {
	sql := "SELECT user_id FROM sessions WHERE session_token = $1"
	var userID string
	err := dbConnection.QueryRow(context.Background(), sql, sessionToken).Scan(&userID)
	checkErr(err)
	return userID
}

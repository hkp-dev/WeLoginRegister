package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"text/template"
)

const userFile = "data/users.json"

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func hashPassword(pwd string) string {
	hash := sha256.New()
	hash.Write([]byte(pwd))
	return hex.EncodeToString(hash.Sum(nil))
}

func loadUsers() ([]User, error) {
	file, err := os.ReadFile(userFile)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	var users []User
	if err = json.Unmarshal(file, &users); err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	return users, nil
}

func saveUser(users []User) error {
	data, err := json.Marshal(users)
	if err != nil {
		return err
	}
	return os.WriteFile(userFile, data, 0644)
}

func RegisterHandle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		email := r.FormValue("email")
		hashedPassword := hashPassword(password)
		fmt.Printf("====================REGISTER====================\n")
		fmt.Printf("Username: %s, Password: %s\n, Email: %s\n", username, password, email)
		users, err := loadUsers()
		if err != nil {
			http.Error(w, "Unable to load user", http.StatusInternalServerError)
			return
		}
		for _, user := range users {
			if user.Username == username {
				http.Error(w, "User already exists", http.StatusConflict)
				return
			}
		}
		newUser := User{
			Username: username,
			Password: hashedPassword,
			Email:    email,
		}
		users = append(users, newUser)

		if err := saveUser(users); err != nil {
			http.Error(w, "Unable to save user", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	template := template.Must(template.ParseFiles("templates/register.html"))
	template.Execute(w, nil)
}

func LoginHandle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")
		fmt.Printf("====================LOGIN====================\n")
		fmt.Printf("Username: %s, Password: %s\n", username, password)
		users, err := loadUsers()
		if err != nil {
			http.Error(w, "Unable to load user", http.StatusInternalServerError)
			return
		}
		hashedPassword := hashPassword(password)
		for _, user := range users {
			if user.Username == username && user.Password == hashedPassword {
				http.SetCookie(w, &http.Cookie{
					Name:  "username",
					Value: user.Username,
					Path:  "/",
				})
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
		}
	}
	template := template.Must(template.ParseFiles("templates/login.html"))
	template.Execute(w, nil)
}
func WelcomeHandle(w http.ResponseWriter, r *http.Request) {
	cokie, err := r.Cookie("username")
	var username string
	if err == nil {
		username = cokie.Value
	}
	data := map[string]interface{}{
		"IsLoggedIn": err == nil,
		"Username":   username,
	}
	template := template.Must(template.ParseFiles("templates/index.html"))
	template.Execute(w, data)
}
func LogOutHandle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		cookie := &http.Cookie{
			Name:   "username",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		}
		http.SetCookie(w, cookie)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}
func main() {
	http.HandleFunc("/login", LoginHandle)
	http.HandleFunc("/register", RegisterHandle)
	http.HandleFunc("/", WelcomeHandle)
	http.HandleFunc("/logout", LogOutHandle)
	var binAddress = "0.0.0.0:8080"
	http.ListenAndServe(binAddress, nil) // setup server
	fmt.Printf("Server listening on: %s\n", binAddress)
}

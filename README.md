# pwdbro
A Golang password strength checker toolkit

### How to get it?

```go
$ go get -u "github.com/hesahesa/pwdbro"
```

### What is this?

This is Golang toolkit to check the strength of a password string. By default it contains three checker mechanism, and can be extended based on your need!

### Default checking mechanism

By default, this toolkit contains 3 password strength checking mechanism, those are:
- nonempty : checks whether a password string contains one or more character (this serves as an example on how to extend the toolkit using your own checker)
- pwnedpasswords : check whether a password string is included in the pwnedpasswords database. Basically it is what https://haveibeenpwned.com/Passwords is doing, but using their API
- zxcvbn : check whether a password string is strong enough according to the Dropbox's zxcvbn algorithm. We also extend the dataset of the algorithm using Indonesian wordlist database! (please refer to the go.mod of this project for more information)

### How to use?

Supposed that you have a password string that you want to check
```go
pwd  := "password"
```
to check using the default pwdbro checking mechanism, use this:
```go
pwdbro := pwdbro.NewDefaultPwdBro()

status, err := pwdbro.RunChecks(pwd)
// or aleternatively, use this to run the checks in parallel
status, err := pwdbro.RunParallelChecks(pwd)
```
you can then evaluate the result:
```go
for _, resp := range status {
	// in practice, you will want to evaluate based on the
	// resp.Safe field and not just printing it
	
	fmt.Println(resp.Safe)
	fmt.Println(resp.Method)
	fmt.Println(resp.Message)
	fmt.Println(resp.Error)
}
```

### Implementing your own checker

To implement your own checking mechanism, you need to create a struct that implements pwdbro.PwdChecker interface, for example:
```go
type MyCheker struct {
}

// MethodName returns the method name of this checker
func (m *MyCheker) MethodName() string {
	return "My Checker Method Name"
}

// CheckPassword returns true if the supplied string is "safe" to use as password
func (m *MyCheker) CheckPassword(pwd string) (bool, string, error) {
	// implements your password checking logic in here
}
```
and then you can add it to an existing pwdbro instance
```go
pwdbro := pwdbro.NewDefaultPwdBro()
// or if you want a pwdbro with no default checkers
pwdbro := pwdbro.NewEmptyPwdBro()

// add your custom checker
pwdbro.AddChecker(&MyChecker{})

// run the checks
status, err := pwdbro.RunChecks(pwd)
```

###### Made with <3 by [@hesahesa]

[@hesahesa]: <http://prahesa.id>

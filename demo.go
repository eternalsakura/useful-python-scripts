package main

import "fmt"

func main() {
	
	s := "abc";
	for i := range s{
		fmt.Println(s[i]);
	}
}
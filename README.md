# webProbe

## About The Project
`webProbe` was developed by Nicholas Albright (nma-io) for testing web connectivity, identifying available protocols, and detecting certificate discrepancies. 

I am using it to test connectivy though security proxies. 

## Features
- **Protocol Identification**: Discover which HTTP protocols (HTTP/1.1, HTTP/2, HTTP/3) a web server supports.
- **Certificate Analysis**: Check for discrepancies and details in SSL/TLS certificates.


## Getting Started
To get started with `webProbe`, you need to have Go installed on your system. You can download Go from [here](https://golang.org/dl/).

### Installation
1. **Clone the repository:**
   `git clone https://github.com/nma-io/webProbe.git`

2. **Navigate to the project directory:**
    `cd webProbe`

3. **Build** 
 `go build -o build --buildvcs=false -ldflags="-s -w" -trimpath -o webProbe webProbe.go`

4. **Run**
    `./webProbe <website URL>`


## Contributing
Any contributions you make are greatly appreciated. - Fork the project and create a PR. 


## License
Distributed under the MIT License. 

Dựa vào các thông tin PAI và API key bên dưới hãy viết cho tôi một MCP cho Metasploit Pro cho tôi với các yêu cầu:
- công nghệ dùng là docker compose chạy nodejs 
- có login bằng authenticator bearer token
- là http MCP chạy cổng 8080 kết nối từ đâu cũng được
- full tính năng của Metasploit Pro có khả năng thêm Project, scan, get report, exploit.... tất cả tính năng có thể có của phần mềm riêng tính năng exploit thì cần có khóa kích hoạt bật true thì auto còn trên false thì không cho phép kích hoạt exploit.
- tất cả thông tin trên đều phải nằm trong file .env
Thông tin về API endpoint:

https://docs.rapid7.com/metasploit/rest-api/
https://docs.rapid7.com/metasploit/rest-api-endpoints/

API key: 13f70b1f7e0a2a3644e21d7f63374dc5
Host: https://localhost:3790
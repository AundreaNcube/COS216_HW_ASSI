# COS216_HW_ASSI
This is for COS216 homework assignment.

#QUICK QUIDE TASK 2 ::
After you install nodeJS and npm please run this code:
->npm install
make sure ur package.json that u will get when you download that it looks like this:

{
  "name": "multi-user-server",
  "version": "1.0.0",
  "description": "WebSocket server for multi-user COS216 HA",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "test": "echo \"No tests implemented yet\" && exit 0"
  },
  "keywords": ["websocket", "nodejs", "server", "multi-user", "cos216"],
  "author": "Amantle Keamogetse Temo (u23539764) and Aundrea Ncube (u22747363)",
  "license": "ISC",
  "dependencies": {
    "axios": "^1.9.0",
    "dotenv": "^16.5.0",
    "ws": "^8.18.1",
    "readline-sync": "^1.4.10",
    "async-mutex": "^0.5.0"
  }
}


with regards to the .env you can just replace with ur details .

#Example of json body to send when you want to test:
{
  "type": "login",
  "email": "amakea45@icloud.com",
  "password": "Amantlekea29#"
}

the other can you please just see the code 

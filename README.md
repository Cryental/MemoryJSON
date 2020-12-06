# MemoryJSON
Memory I/O Engine with JSON Files

This project using the modified Memory.dll as a main I/O engine.

This library will allow you to create trainers very easily with JSON files, without working on codes.

#### Warning!
Please do not use this library for multi player games. I created this library to create single player trainers easily. You will get banned if you use it in multi player, please use this at your own risk.

Example offsets are all dummy offsets, they won't work in the real game.

This project is under development. Do not use for production.

### How to Use:
```cs
var memoryengine = new MemoryJSON.Engine();

// Encrypt AmberJSON file
memoryengine.EncryptFile("among us.amber", "among us_output.amber", "password");


// Local Access
var trainer = memoryengine.CreateTrainerFromFile("among us.amber");

// Local Access with Password
var trainer = memoryengine.CreateTrainerFromFile("among us.amber", "password");

// Remote Access with URL
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.amber");

// Remote Access with URL and Password
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.amber", "password");

// Remote Access with URL, Password, Username and User Password (Http Basic Auth)
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.amber", "password", "username", "userpass");



// Inject to the Game Process. (Boolean Type)
trainer.Inject2Game();

// It's required to run with Inject2Game always. 
// If it returns false, you cannot use any functions.
// It can cause some lags and delay if you need to scan AoB. Please use async method in your code. 
trainer.InitEngine();

// Get Tab
var generalTrainers = trainer.FindTab("General");

// Get List of Functions
var functions = generalTrainers.GetAllFunctions();
// Returns String with boolean or number. You can use Enable and Disable for boolean type, and use SetValve for the number type.
var getFunctionType = generalTrainers["Show Ghosts"].GetType(); 

// Use Functions
generalTrainers.SearchFunction("Movement Speed").SetValve("1");

generalTrainers.SearchFunction("Show Ghosts").Enable();
generalTrainers.SearchFunction("Show Ghosts").Disable();

// Create Executable File (Not available yet, under development)
trainer.GenerateEXE("filePath");
trainer.GenerateEXE("filePath", "customBackgroundImagePath");
```

### AmberJSON Format:

This engine uses AmberJSON as the script format. (*.amber)

For the `function` field, it supports almost all features from Memory.dll. For read memory functions, you will need to use it like:

```
{
  "function": "ReadInt",
  "defineName": "readedInt",
  "address": "address"
},
{
  "function": "WriteMemory",
  "address": "Game.dll+6E",
  "type": "int",
  "value": "{{@readedInt}}"
}
```
The defined variable will only be available in the same procedures.

`version` will be FileVersion from properties of the game file. It will allow running if the version is the same, otherwise, it will return an exception. If you don't want to use this feature, use "all" in the field.

#### Prefix:
- All defined variables by aobScan: `?` (Ex: `{{?PlayerControl_GetData}}`)
- All defined variables by offsets: `#` (Ex: `{{#ShowGhosts}}`)
- All defined variables in procedures: `@` (Ex: `{{@readedInt}}`)
- SetValue Prefix: `{{$customValue}}`

#### Example:
```json
{
  "name": "Among Us",
  "description": "Trainer for Among Us",
  "processName": "Among Us",
  "version": "2019.4.9.65162",
  "offsets": [
    {
      "name": "ShowGhosts",
      "value": "GameAssembly.dll+20E7BB"
    },
    {
      "name": "MovementSpeed",
      "value": "GameAssembly.dll+00DA9DE4,24,20,5C,24,14"
    }
  ],
  "aobScan": [
    {
      "name": "PlayerControl_GetData",
      "value": "55 8B EC 80 3D EC C8 ??",
      "startAddress": "",
      "endAddress": "",
      "writable": false,
      "executable": false,
      "regions": [
        "0x400000",
        "0x800000"
      ]
    }
  ],
  "trainers": [
      {
        "tabName": "General",
        "functions": [
          {
            "name": "Show Ghosts",
            "enabled": {
              "procedures": [
                {
                  "function": "WriteMemory",
                  "address": "{{#ShowGhosts}}",
                  "type": "bytes",
                  "value": "{{?PlayerControl_GetData}}"
                }
              ]
            },
            "disabled": {
              "procedures": [
                {
                  "function": "WriteMemory",
                  "address": "{{#ShowGhosts}}",
                  "type": "bytes",
                  "value": "{{?PlayerControl_GetData}}"
                }
              ]
            }
          },
          {
            "name": "Movement Speed",
            "setValue": {
              "procedures": [
                {
                  "function": "WriteMemory",
                  "address": "{{#MovementSpeed}}",
                  "type": "float",
                  "value": "{{$customValue}}"
                }
              ]
            }
          },
          {
            "name": "Infinity Kill Range",
            "enabled": {
              "procedures": [
                {
                  "function": "CreateCodeCave",
                  "address": "GameAssembly.dll+6EE",
                  "newBytes": "C7 44 06 10 00 00 80",
                  "replaceCount": 6,
                  "size": 4096
                },
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE5",
                  "type": "bytes",
                  "value": "72 12"
                }
              ]
            },
            "disabled": {
              "procedures": [
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE5",
                  "type": "bytes",
                  "value": "F3 0F 10 44 86 10 A1"
                },
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE3",
                  "type": "bytes",
                  "value": "75 12"
                }
              ]
            }
          }
        ]
      }
  ]
}
```

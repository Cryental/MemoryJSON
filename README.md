# MemoryJSON.NET
Memory I/O Engine with JSON Files

This project using the modified Memory.dll as a main I/O engine.

This library will allow you to create trainers very easily with JSON files, without working on codes.

This project is under development. Do not use for production.

### How to Use:
```cs
var memoryengine = new MemoryJSON.Engine();

// Local Access
var trainer = memoryengine.CreateTrainerFromFile("among us.json");

// Local Access with Password
var trainer = memoryengine.CreateTrainerFromFile("among us.json", "password");

// Remote Access with URL
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.json");

// Remote Access with URL and Password
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.json", "password");

// Remote Access with URL, Password, Username and User Password (Http Basic Auth)
var trainer = memoryengine.CreateTrainerFromURL("http://example.com/among us.json", "password", "username", "userpass");

// Inject to the Game Process. (Boolean Type)
trainer.Inject2Game();

// Run pre-processing table. It has all AoBScan data that might be required for running functions. (Boolean Type)
trainer.RunPreProcessing();

// Get Tab
var generalTrainers = trainer.FindTab("General");

// Get List of Functions
var functions = generalTrainers.GetAllFunctions();
// Returns String with boolean, float, int, etc. You can use Enable and Disable for boolean type, and use SetValve for other number types.
var getFunctionType = generalTrainers["Show Ghosts"].GetType(); 

// Use Functions
generalTrainers.SearchFunction("Movement Speed").SetValve("1");

generalTrainers.SearchFunction("Show Ghosts").Enable();
generalTrainers.SearchFunction("Show Ghosts").Disable();
```

### JSON Scripting Format:
```json
{
  "name": "Among Us",
  "description": "Trainer for Among Us",
  "processName": "Among Us",
  "preprocessing": [
    {
      "type": "variable",
      "name": "Offset_ShowGhosts",
      "value": "GameAssembly.dll+20E7BB"
    },
    {
      "type": "variable",
      "name": "Offset_MovementSpeed",
      "value": "GameAssembly.dll+00DA9DE4,24,20,5C,24,14"
    },
    {
      "type": "aobscan",
      "name": "AoB_PlayerControl_GetData",
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
    [
      {
        "tabName": "General",
        "functions": [
          {
            "name": "Show Ghosts",
            "enabled": {
              "triggers": [
                {
                  "function": "WriteMemory",
                  "address": "{{Offset_ShowGhosts}}",
                  "type": "bytes",
                  "value": "80 7F 29 05 0F 85"
                }
              ]
            },
            "disabled": {
              "triggers": [
                {
                  "function": "WriteMemory",
                  "address": "{{Offset_ShowGhosts}}",
                  "type": "bytes",
                  "value": "80 7F 29 00 0F 84"
                }
              ]
            }
          },
          {
            "name": "Movement Speed",
            "setValue": {
              "triggers": [
                {
                  "function": "WriteMemory",
                  "address": "{{Offset_MovementSpeed}}",
                  "type": "float",
                  "value": "{customValue}"
                }
              ]
            }
          },
          {
            "name": "Infinity Kill Range",
            "enabled": {
              "triggers": [
                {
                  "function": "CreateCodeCave",
                  "address": "GameAssembly.dll+6EE35B",
                  "newBytes": "C7 44 06 10 00 00 80 7F F3 0F 10 44 06 10",
                  "replaceCount": 6,
                  "size": 4096
                },
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE55A",
                  "type": "bytes",
                  "value": "72 12"
                }
              ]
            },
            "disabled": {
              "triggers": [
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE55A",
                  "type": "bytes",
                  "value": "F3 0F 10 44 86 10 A1"
                },
                {
                  "function": "WriteMemory",
                  "address": "GameAssembly.dll+6EE35B",
                  "type": "bytes",
                  "value": "75 12"
                }
              ]
            }
          }
        ]
      }
    ]
  ]
}
```

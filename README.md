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

// Get List of Functions
var functions = trainer.GetAllFunctions();
// Returns String with boolean, float, int, etc. You can use Enable and Disable for boolean type, and use SetValve for other number types.
var getFunctionType = functions["Show Ghosts"].GetType(); 

trainer.SearchFunction("MovementSpeed").SetValve("1");

trainer.SearchFunction("Show Ghosts").Enable();
trainer.SearchFunction("Show Ghosts").Disable();
```

### JSON Format:
```json
{
  "name": "Among Us",
  "description": "Trainer for Among Us",
  "processName": "Among Us",
  "trainers": [
    {
      "name": "Show Ghosts",
      "enabled": {
        "triggers": [
          {
            "function": "WriteMemory",
            "address": "GameAssembly.dll+20E7BB",
            "type": "bytes",
            "value": "80 7F 29 05 0F 85"
          }
        ]
      },
      "disabled": {
        "triggers": [
          {
            "function": "WriteMemory",
            "address": "GameAssembly.dll+20E7BB",
            "type": "bytes",
            "value": "80 7F 29 00 0F 84"
          }
        ]
      }
    }
  ]
}
```

# MemoryJSON.NET
Memory I/O Engine with JSON Files

This project using the modified Memory.dll as a main I/O engine.

This library will allow you to create trainers very easily with JSON files, without working on codes.

This project is under development. Do not use for production.

### How to Use:
```cs
var memoryengine = new MemoryJSON.Engine();
var trainer = memoryengine.CreateTrainerFromFile("among us.json");

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

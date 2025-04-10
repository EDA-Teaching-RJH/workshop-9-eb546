# UK Nuclear Simulation Platform

This project simulates a UK Nuclear Control system using C programming. It consists of multiple components that communicate with each other to simulate command and control operations.

## Components

- `nuclearControl.c`: The main server application that coordinates communication.
- `missileSilo.c`: Launches missiles upon receiving verified commands.
- `submarine.c`: Provides intelligence and can launch missiles.
- `radar.c`: Provides intelligence to the control server.
- `satellite.c`: Provides intelligence to the control server.

## Build Instructions

To compile the project, run:

```bash
make


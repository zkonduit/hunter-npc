## Hunter NPC

Creates a simple hunter NPC that follows the player and in a 2D environment. The hunter will pick the next step that minimizes the distance to the player.

## Quickstart

- Dependency management is handled by pdm, install pdm
```shell
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

- Install dependencies. Note that this will create a virtual environment for you
```shell
pdm install
```

- Activate python environment
```shell
# use pdm venve activate to get the command to activate virtual env
source .venv/bin/activate
```

- Open up jupyter, and navigate to the url provided if it doesn't already open up the browser session
```shell
jupyter-lab

# then go to the link provided via the CLI
```

You can then run the notebook in `notebooks/npc.ipynb` the outputs of this will be 
- sprover and verifier key pairs for the zkSNARK of the hunter NPC
- evm contract code for the hunter NPC verifier


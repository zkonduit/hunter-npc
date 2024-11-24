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
- prover and verifier key pairs for the zkSNARK of the hunter NPC
- EVM contract code for the hunter NPC verifier

You can find sample contracts (and corresponding abi) in the `outputs` directory.

### Lifecycle of a proof 

1. call `ezkl.gen_witness` when the state on chain updates (eg. the player moves and now you need to update the hunter) to create a new `proposed_output`.
2. call `ezkl.prove` to generate a new proof for that data.
3. call some (not inplemented here) wrapper contract with an `updateState(proof, proposed_move)` method which governs new moves for the NPC on-chain.
4. this function will make a subcall to the ezkl verifier's `verifyProof` method where `calldata proof` is the proof it has received and `instances` is the concatenation of current_state and proposed_move into a flat array (`instances = [player_x, player_y, hunter_x, hunter_y, proposed_move]`). The verifier will return a boolean value indicating whether the proof is valid or not.

This lifecycle can easily be automated with a bot that listens to the chain and updates the hunter NPC state accordingly. We can do this using the `web3` library in python, the ezkl `lilith` cluster, or directly in the player's browser using the [ezkl JS bindings](https://registry.npmjs.org/@ezkljs%2fengine) (i.e the player when they move have to also compute a proof for the hunter's move -- they sort of run their own enemy as well). 

TODOs:
- [ ] build a sample bot using web3
- [ ] build a sample bot using the ezkl lilith cluster
- [ ] build a flow for the player to also compute a proof for the hunter's move in the browser




.PHONY: dataset api test ml

dataset:
	python -m simulator.generate_dataset --count 5000

api:
	python run.py

test:
	pytest

ml:
	python -m ml.train_model --model random_forest

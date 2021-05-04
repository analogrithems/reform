from invoke import Collection, Program
from reform import tasks

program = Program(namespace=Collection.from_module(tasks), version="0.2.1")

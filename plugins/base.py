"""Plugin base contract for future RAVEN modules."""


class BaseModule:
    name = "base"
    description = "Base module"

    def run(self, context):
        raise NotImplementedError

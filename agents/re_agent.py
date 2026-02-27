class REAgent:
    def __init__(self, model):
        self.model = model

    async def run(self, sample):
        context = {}
        for step in self.steps:
            prompt = step["prompt"].format(**sample)
            response = await self.model(prompt)
            context[step["name"]] = response
        return context
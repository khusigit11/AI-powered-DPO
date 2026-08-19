import anthropic
from flask import current_app


def ask_claude(prompt):
    """
    sends a prompt to claude and gets a response back
    this is the brain behind all 7 dpo tasks
    """
    api_key = current_app.config.get('ANTHROPIC_API_KEY')

    if not api_key:
        return "Error: No API key found. Please set ANTHROPIC_API_KEY."

    try:
        client = anthropic.Anthropic(api_key=api_key)

        message = client.messages.create(
            model="claude-sonnet-4-6",    
            max_tokens=2000,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            system="You are an AI-powered Data Protection Officer assistant. You help organisations comply with GDPR by generating documents, assessing compliance, evaluating risks, drafting responses and providing data protection guidance. Keep your responses professional, clear and actionable."
        )

        # pull the text out of claude's response
        return message.content[0].text

    except Exception as e:
        return f"Error connecting to AI: {str(e)}"
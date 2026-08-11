from app import create_app

# Create the Flask application
app = create_app()

if __name__ == '__main__':
    print("")
    print("=" * 50)
    print("  AI-Powered Data Protection Officer (AI-DPO)")
    print("  COMP7039 MSc Dissertation")
    print("  Oxford Brookes University")
    print("=" * 50)
    print("")
    print("  Default login accounts:")
    print("  Admin  -> username: admin    | password: admin123")
    print("  User   -> username: testuser | password: user123")
    print("")
    print("  Open in browser: http://127.0.0.1:5000")
    print("=" * 50)
    print("")

    # Start the app in debug mode (auto-reloads when you change code)
    app.run(debug=True, host='0.0.0.0', port=5000)
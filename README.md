# Email Analyzer Pro

## Overview

Email Analyzer Pro is a modern web application designed to provide advanced analysis capabilities for email-related data. Built with React, Vite, and a Node.js/Express backend, it leverages a rich set of UI components and tools to offer a robust and interactive user experience.

## Features

*   **Interactive User Interface**: Developed with React and a comprehensive set of Radix UI components, ensuring a responsive and intuitive experience.
*   **Backend API**: A Node.js/Express server handles data processing and API requests.
*   **Modern Tooling**: Utilizes Vite for fast development and optimized builds, and pnpm for efficient dependency management.
*   **TypeScript Support**: Enhances code quality and maintainability with static type checking.
*   **Styling**: Integrated with Tailwind CSS for utility-first styling.

## Prerequisites

Before you begin, ensure you have the following installed:

*   **Node.js**: Version 18 or higher (LTS recommended).
*   **pnpm**: A fast, disk space efficient package manager. You can install it globally using npm:
    ```bash
    npm install -g pnpm
    ```

## Installation

1.  **Clone the repository** (if you haven't already):
    ```bash
bash
    git clone https://github.com/YOUR_USERNAME/email-analyzer-pro.git
    cd email-analyzer-pro
    ```
    *(Note: Replace `YOUR_USERNAME` with your actual GitHub username.)*

2.  **Install dependencies**:
    ```bash
    pnpm install
    ```

## Running the Project

### Development Mode

To run the project in development mode with hot-reloading:

```bash
pnpm run dev
```

This will start the Vite development server, typically accessible at `http://localhost:5173` (or another port if 5173 is in use).

### Production Mode

First, build the project:

```bash
pnpm run build
```

Then, start the production server:

```bash
pnpm run start
```

This will serve the optimized production build.

## Building the Project

To create an optimized production build of the client and server:

```bash
pnpm run build
```

The client assets will be built by Vite, and the server-side TypeScript code will be compiled to JavaScript using `esbuild` into the `dist` directory.

## Deploying to GitHub

Since you've already created a repository on GitHub, you can push this local project to it using the following commands. Make sure you are in the root directory of your project (`email-analyzer-pro`).

```bash
git init
git add .
git commit -m "Initial commit of Email Analyzer Pro"
git branch -M main
git remote add origin https://github.com/xyra-HA/email-analyzer-pro.git
git push -u origin main
```

*   **`git init`**: Initializes a new Git repository in your project directory.
*   **`git add .`**: Stages all changes in the current directory for the next commit.
*   **`git commit -m "Initial commit of Email Analyzer Pro"`**: Records the staged changes to the repository with a descriptive message.
*   **`git branch -M main`**: Renames your current branch to `main` (a common practice).
*   **`git remote add origin https://github.com/xyra-HA/email-analyzer-pro.git`**: Connects your local repository to the remote GitHub repository you created. Make sure the URL matches your repository's URL.
*   **`git push -u origin main`**: Pushes your local `main` branch to the `origin` (your GitHub repository) and sets it as the upstream branch, so future `git push` commands are simpler.

After running these commands, your project will be available on your GitHub repository.

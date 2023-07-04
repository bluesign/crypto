name: Reporting a Problem/Bug
description: Reporting a Problem/Bug
labels: [Bug, Feedback]
assignees: tarakby
body:
  - type: markdown
    attributes:
      value: |
        > **Warning**
        > Do you experience an unexpected result or a crash?
        > Please do **NOT** report it as a bug!
        >
        > Instead, report it as a security issue:
        > https://flow.com/flow-responsible-disclosure
  - type: textarea
    attributes:
      label: Current Behavior
      description: A concise description of what you're experiencing.
    validations:
      required: true
  - type: textarea
    attributes:
      label: Expected Behavior
      description: A concise description of what you expected to happen.
    validations:
      required: true
  - type: textarea
    attributes:
      label: Steps To Reproduce
      description: Please share any details and steps that can reproduce the problem
    validations:
      required: true
  - type: textarea
    attributes:
      label: Environment
      description: |
        Example:
          - **Go version**: go1.19
          - **gcc**: x86_64-apple-darwin22.5.0
      render: markdown
    validations:
      required: true
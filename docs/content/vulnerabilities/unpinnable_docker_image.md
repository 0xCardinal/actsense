# Unpinnable Docker Image

## Vulnerability Description


Docker action uses mutable tag {tag} instead of an immutable digest.
This creates security risks:

- Tags can be moved to point to different images

- Tags can be deleted and recreated

- If the image registry is compromised, tags can be moved to malicious images

- Your workflow would automatically use the new (potentially malicious) image


Security concerns:

- Supply chain attacks through tag manipulation

- Malicious images can be deployed automatically

- Image immutability is not guaranteed

- Difficult to verify the exact image being used


## Recommendation


Use Docker image digest instead of tags:


1. Get the image digest:

docker pull {image}

docker inspect {image} | grep RepoDigests

# Or use: docker image inspect {image} --format={{{{.RepoDigests}}}}


2. Update the action to use digest:

runs:

using: docker

image: docker://{image.split(:)[0]}@sha256:<digest>


3. Or use the full digest format:

image: {image.split(:)[0]}@sha256:abc123...


4. Verify the digest is correct:

- The digest should start with sha256:

- The digest is 64 hexadecimal characters

- Verify at the image registry


5. Update all Docker actions to use digests


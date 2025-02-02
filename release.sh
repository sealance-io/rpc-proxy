# #!/bin/bash
# set -exuo pipefail

# user="gochain"
# image="rpc-proxy"
# gcr_project="gochain-core"

# # ensure working dir is clean
# git status
# if [[ -z $(git status -s) ]]
# then
#   echo "tree is clean"
# else
#   echo "tree is dirty, please commit changes before running this"
#   exit 1
# fi

# version_file="version.go"
# docker create -v /data --name file alpine /bin/true
# docker cp $version_file file:/data/$version_file
# # Bump version, patch by default - also checks if previous commit message contains `[bump X]`, and if so, bumps the appropriate semver number - https://github.com/treeder/dockers/tree/master/bump
# docker run --rm -it --volumes-from file -w / treeder/bump --filename /data/$version_file "$(git log -1 --pretty=%B)"
# docker cp file:/data/$version_file $version_file
# version=$(grep -m1 -Eo "[0-9]+\.[0-9]+\.[0-9]+" $version_file)
# echo "Version: $version"

# make docker

# git add -u
# git commit -m "$image: $version release [skip ci]"
# git tag -f -a "$version" -m "version $version"
# git push
# git push origin $version

# # Push docker hub images
# docker tag $user/$image:latest $user/$image:$version
# docker push $user/$image:$version
# docker push $user/$image:latest

# # Push GCR docker images
# ./tmp/google-cloud-sdk/bin/gcloud auth activate-service-account --key-file=${HOME}/gcloud-service-key.json
# docker tag $user/$image:latest gcr.io/$gcr_project/$image:latest
# docker tag $user/$image:latest gcr.io/$gcr_project/$image:$version
# docker push gcr.io/$gcr_project/$image:latest
# docker push gcr.io/$gcr_project/$image:$version
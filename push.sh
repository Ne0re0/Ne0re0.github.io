/bin/rm -rf public/*

hugo build

git add .

git commit -m "Update"

git push 

git subtree push --prefix public/ origin gh-pages

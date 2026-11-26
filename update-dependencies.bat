git switch main
git branch -D deps/update-all
git switch -c deps/update-all

call npx npm-check-updates -u
call npm install
call npm run build

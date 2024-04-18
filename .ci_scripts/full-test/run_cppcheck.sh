EXITCODE=0

# Pattern matching on all source files
for file in $(find $GITHUB_WORKSPACE/include $GITHUB_WORKSPACE/src $GITHUB_WORKSPACE/devices $GITHUB_WORKSPACE/test -name *.h -o -name *.c)
do
    if [[ "$file" != *"/hashmap.c" ]]
    then
        # Run cppcheck on each file
        cppcheck --error-exitcode=1 "$file"
        # If the exit code is not 0, set EXITCODE to 1
        if [[ $? -ne 0 ]]
        then
            EXITCODE=1
        fi
    fi
done

exit $EXITCODE

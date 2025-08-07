EXITCODE=0
PARSERS_DIR="src/parsers"

# Pattern matching on all source files
for file in $(find include src devices test "$PARSERS_DIR"/include "$PARSERS_DIR"/src "$PARSERS_DIR"/test -name *.h -o -name *.c)
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

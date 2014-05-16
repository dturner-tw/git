#!/bin/sh
#
# Copyright (c) 2014 Twitter, Inc
#

test_description='Watchman'

. ./test-lib.sh

if ! test_have_prereq WATCHMAN
then
	skip_all='skipping watchman tests - no watchman'
	test_done
fi

xpgrep () {
	result=$(ps xopid,comm | grep " $1\$" | awk '{ print $1 }')
	echo $result
	test "x$result" != "x"
}

kill_watchman() {
	#stop watchman
	xpgrep watchman | xargs kill
}

#make sure that watchman is not running, but that it is runnable
test_expect_success setup '
	git config core.usewatchman true &&
	#watchman is maybe running
	xpgrep watchman > running-watchman
	grep . running-watchman > /dev/null && kill $(cat running-watchman)
	rm running-watchman &&
	sleep 0.25 &&
	#watchman is stopped
	! xpgrep watchman > /dev/null &&
	#watchman is startable
	watchman &&
	kill_watchman
'

cat >expect <<\EOF
?? expect
?? morx
?? output
EOF

test_expect_success 'watchman sees new files' '
	touch morx &&
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? expect
?? output
EOF

test_expect_success 'watchman sees file deletion' '
	rm morx &&
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
?? bramp
EOF

test_expect_success 'watchman understands .gitignore' '
	touch bramp &&
	cat >.gitignore <<-EOF &&
	expect*
	output*
EOF
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
EOF

test_expect_success 'watchman notices changes to .gitignore' '
	cat >.gitignore <<-EOF &&
	expect*
	output*
	bramp
EOF
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
EOF

test_expect_success 'watchman understands .git/info/exclude' '
	touch fleem &&
	cat >.git/info/exclude <<-EOF &&
	fleem
EOF
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
?? fleem
EOF

test_expect_success 'watchman notices changes to .git/info/exclude' '
	touch crubbins &&
	cat >.git/info/exclude <<-EOF &&
	crubbins
EOF
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
?? crubbins
?? fleem
EOF

test_expect_success 'watchman notices removal of .git/info/exclude' '
	rm .git/info/exclude &&
	git status -s > output &&
	test_cmp expect output &&
	rm crubbins bramp fleem
'


cat >expect <<\EOF
?? .gitignore
?? fleem
?? myignore
EOF

test_expect_success 'watchman notices changes to file configured by core.excludesfile' '
	touch fleem &&
	touch crubbins &&
	cat >myignore <<-EOF &&
	crubbins
EOF
	git config core.excludesfile myignore &&
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
?? crubbins
?? myignore
?? myignore2
EOF

test_expect_success 'watchman notices changes to config variable core.excludesfile' '
	touch fleem &&
	touch crubbins &&
	cat >myignore2 <<-EOF &&
	fleem
EOF
	git config core.excludesfile myignore2 &&
	git status -s > output &&
	test_cmp expect output
'

cat >expect <<\EOF
?? .gitignore
?? crubbins
?? fleem
?? myignore
EOF

test_expect_success 'watchman notices removal of file referred to by' '
	rm myignore2 &&
	git status -s > output &&
	test_cmp expect output &&
	rm crubbins fleem myignore
'


cat >expect.nothing <<\EOF
EOF

cat >expect.2 <<\EOF
EOF

test_expect_success 'git diff still works' '
	echo 1 > diffy &&
	git add diffy .gitignore &&
	git commit -m initial &&
	git status -s > output &&
	test_cmp expect.nothing output &&
	echo 2 >> diffy &&
	test_cmp expect.2 output
'

cat >expect <<\EOF
 D diffy
EOF

test_expect_success 'file to directory changes still work' '
	rm diffy &&
	mkdir diffy &&
	touch diffy/a &&
	git status -s > output &&
	test_cmp expect output &&
	git add diffy/a &&
	git commit -m two &&
	git status -s > output.nothing
'

cat >expect <<\EOF
 D diffy/a
?? diffy
EOF

test_expect_success 'directory to file changes still work' '
	rm -r diffy &&
	touch diffy &&
	git status -s > output &&
	test_cmp expect output &&
	rm diffy &&
	git rm diffy/a &&
	git commit -m "remove diffy"
'

cat >expect <<\EOF
?? dead
EOF

test_expect_success 'changes while watchman is not running are detected' '
	kill_watchman &&
	sleep 0.25 &&
	! xpgrep watchman > /dev/null &&
	touch dead &&
	git status -s > output &&
	test_cmp expect output
'

test_expect_success 'Restore default test environment' '
	git config --unset core.usewatchman &&
	kill_watchman
'

test_done

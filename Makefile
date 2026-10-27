.PHONY: all check paper l4re-build l4re-hello check-l4re-hello l4re-zcomp-build l4re-zcomp check-l4re-zcomp bench-l4re-zcomp
all:
	cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cmake --build build -j

check: all
	ctest --test-dir build --output-on-failure

# 原稿のディレクトリで設定を読み、実装のビルドと独立してPDFを生成する。
paper:
	cd paper/comsys2026 && latexmk -pdfdvi -interaction=nonstopmode -file-line-error main.tex

# Linux参照実装とは別に公式helloだけを起動し、互換レイヤーの成果と混同しない。
l4re-build:
	bash tools/l4re-hello.sh build

l4re-hello:
	bash tools/l4re-hello.sh run

check-l4re-hello:
	bash tools/l4re-hello.sh check

l4re-zcomp-build:
	bash tools/l4re-zcomp.sh build

l4re-zcomp:
	bash tools/l4re-zcomp.sh run

check-l4re-zcomp:
	bash tools/l4re-zcomp.sh check

bench-l4re-zcomp:
	bash tools/l4re-bench.sh

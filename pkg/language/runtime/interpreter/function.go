package interpreter

import (
	"github.com/raviqqe/hamt"

	"github.com/dapperlabs/bamboo-node/pkg/language/runtime/ast"
	"github.com/dapperlabs/bamboo-node/pkg/language/runtime/sema"
	. "github.com/dapperlabs/bamboo-node/pkg/language/runtime/trampoline"
)

// FunctionValue

type FunctionValue interface {
	Value
	isFunctionValue()
	invoke(interpreter *Interpreter, arguments []Value) Trampoline
	parameterCount() int
}

// InterpretedFunctionValue

type InterpretedFunctionValue struct {
	Expression *ast.FunctionExpression
	Activation hamt.Map
}

func (InterpretedFunctionValue) isValue() {}

func (f InterpretedFunctionValue) Copy() Value {
	return f
}

func (InterpretedFunctionValue) isFunctionValue() {}

func newInterpretedFunction(expression *ast.FunctionExpression, activation hamt.Map) InterpretedFunctionValue {
	return InterpretedFunctionValue{
		Expression: expression,
		Activation: activation,
	}
}

func (f InterpretedFunctionValue) invoke(interpreter *Interpreter, arguments []Value) Trampoline {
	return interpreter.invokeInterpretedFunction(f, arguments)
}

func (f InterpretedFunctionValue) parameterCount() int {
	return len(f.Expression.Parameters)
}

// HostFunctionValue

type HostFunction func(interpreter *Interpreter, arguments []Value) Trampoline

type HostFunctionValue struct {
	Type     *sema.FunctionType
	Function HostFunction
}

func (HostFunctionValue) isValue() {}

func (f HostFunctionValue) Copy() Value {
	return f
}

func (HostFunctionValue) isFunctionValue() {}

func (f HostFunctionValue) invoke(interpreter *Interpreter, arguments []Value) Trampoline {
	return f.Function(interpreter, arguments)
}

func (f HostFunctionValue) parameterCount() int {
	return len(f.Type.ParameterTypes)
}

func NewHostFunctionValue(
	functionType *sema.FunctionType,
	function HostFunction,
) HostFunctionValue {
	return HostFunctionValue{
		Type:     functionType,
		Function: function,
	}
}

// StructFunctionValue

type StructFunctionValue struct {
	function  InterpretedFunctionValue
	structure StructureValue
}

func (*StructFunctionValue) isValue() {}

func (*StructFunctionValue) isFunctionValue() {}

func (f *StructFunctionValue) parameterCount() int {
	// TODO:
	return 0
}

func (f *StructFunctionValue) Copy() Value {
	functionCopy := *f
	return &functionCopy
}

func (f *StructFunctionValue) CopyWithStructure(structure StructureValue) *StructFunctionValue {
	functionCopy := *f
	functionCopy.structure = structure
	return &functionCopy
}

func (f *StructFunctionValue) invoke(interpreter *Interpreter, arguments []Value) Trampoline {
	return interpreter.invokeStructureFunction(
		f.function,
		arguments,
		f.structure,
	)
}

func NewStructFunction(
	function InterpretedFunctionValue,
	structure StructureValue,
) *StructFunctionValue {
	return &StructFunctionValue{
		function,
		structure,
	}
}

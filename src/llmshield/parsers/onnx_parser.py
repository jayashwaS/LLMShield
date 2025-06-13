"""Parser for ONNX model files."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import onnx
from onnx import helper, checker

from llmshield.core.logger import get_logger
from llmshield.core.exceptions import FileParsingError, CorruptedFileError
from llmshield.parsers.base import BaseParser, ParserResult, ModelMetadata

logger = get_logger()


class ONNXParser(BaseParser):
    """Parser for ONNX model files (.onnx)."""
    
    SUPPORTED_EXTENSIONS: Set[str] = {'.onnx'}
    FRAMEWORK_NAME: str = "onnx"
    
    def validate_format(self, file_path: Path) -> bool:
        """Validate that the file is a valid ONNX file."""
        try:
            # Try to load the model
            onnx_model = onnx.load(str(file_path))
            # Validate model structure
            checker.check_model(onnx_model)
            return True
        except Exception:
            return False
    
    def parse(self, file_path: Path) -> ParserResult:
        """Parse ONNX model file."""
        logger.info(f"Parsing ONNX file: {file_path}")
        
        metadata = self.extract_metadata(file_path)
        warnings = []
        suspicious_patterns = []
        embedded_code = []
        external_dependencies = []
        
        try:
            # Load ONNX model
            model = onnx.load(str(file_path))
            
            # Extract basic metadata
            metadata.framework_version = f"opset_{model.opset_import[0].version}"
            
            # Extract model metadata
            if model.metadata_props:
                meta_dict = {}
                for prop in model.metadata_props:
                    meta_dict[prop.key] = prop.value
                    # Check for suspicious metadata
                    if any(suspicious in prop.key.lower() for suspicious in 
                          ['exec', 'eval', 'code', 'script', 'command']):
                        warnings.append(f"Suspicious metadata key: {prop.key}")
                        suspicious_patterns.append(prop.key)
                
                metadata.custom_attributes['metadata'] = meta_dict
            
            # Extract graph information
            graph = model.graph
            metadata.model_architecture = graph.name or "unnamed"
            
            # Analyze nodes
            node_types = {}
            custom_ops = []
            
            for node in graph.node:
                op_type = node.op_type
                node_types[op_type] = node_types.get(op_type, 0) + 1
                
                # Check for custom operations
                if op_type.startswith('custom.') or op_type not in self._get_standard_ops():
                    custom_ops.append(op_type)
                    warnings.append(f"Custom operation detected: {op_type}")
                    suspicious_patterns.append(f"custom_op:{op_type}")
                
                # Check for suspicious attributes
                for attr in node.attribute:
                    if attr.type == onnx.AttributeProto.STRING:
                        # Check string attributes for suspicious content
                        if hasattr(attr, 's'):
                            string_value = attr.s.decode('utf-8', errors='ignore')
                            suspicious = self.check_suspicious_imports(string_value)
                            if suspicious:
                                warnings.append(f"Suspicious string in node {node.name}: {suspicious}")
                                suspicious_patterns.extend(suspicious)
            
            metadata.custom_attributes['node_types'] = node_types
            metadata.custom_attributes['custom_operations'] = custom_ops
            
            # Count parameters
            total_params = 0
            for initializer in graph.initializer:
                total_params += len(initializer.raw_data) // 4  # Assuming float32
            metadata.parameters_count = total_params
            
            # Extract layer information
            layers = []
            for node in graph.node:
                layer_info = {
                    'name': node.name,
                    'op_type': node.op_type,
                    'inputs': list(node.input),
                    'outputs': list(node.output),
                }
                layers.append(layer_info)
            metadata.layers = layers[:20]  # Limit to first 20 layers
            
            # Check for external data
            for initializer in graph.initializer:
                if initializer.HasField('data_location') and \
                   initializer.data_location == onnx.TensorProto.EXTERNAL:
                    external_dependencies.append(f"external_data:{initializer.name}")
                    warnings.append(f"Model references external data: {initializer.name}")
            
            # Check model size vs actual parameters
            expected_size = total_params * 4  # float32
            actual_size = file_path.stat().st_size
            if actual_size > expected_size * 1.5:
                warnings.append("Model file larger than expected - may contain hidden data")
            
        except Exception as e:
            logger.error(f"Error parsing ONNX file: {e}")
            warnings.append(f"Parse error: {str(e)}")
        
        return ParserResult(
            metadata=metadata,
            warnings=warnings,
            suspicious_patterns=suspicious_patterns,
            embedded_code=embedded_code,
            external_dependencies=external_dependencies,
            serialization_format="onnx"
        )
    
    def _get_standard_ops(self) -> Set[str]:
        """Get set of standard ONNX operations."""
        # This is a subset of common ONNX ops
        return {
            'Add', 'Sub', 'Mul', 'Div', 'MatMul', 'Gemm',
            'Conv', 'ConvTranspose', 'MaxPool', 'AveragePool',
            'GlobalMaxPool', 'GlobalAveragePool',
            'BatchNormalization', 'InstanceNormalization',
            'Dropout', 'Relu', 'LeakyRelu', 'Prelu', 'Elu',
            'Selu', 'Sigmoid', 'Tanh', 'Softmax', 'LogSoftmax',
            'Softplus', 'Softsign', 'HardSigmoid', 'HardSwish',
            'Identity', 'Reshape', 'Flatten', 'Squeeze', 'Unsqueeze',
            'Transpose', 'Concat', 'Split', 'Slice', 'Pad',
            'Gather', 'GatherElements', 'Scatter', 'ScatterElements',
            'Cast', 'Clip', 'Where', 'NonZero', 'NonMaxSuppression',
            'TopK', 'ReduceMax', 'ReduceMin', 'ReduceMean', 'ReduceSum',
            'ReduceProd', 'ReduceL1', 'ReduceL2', 'ReduceLogSum',
            'ReduceLogSumExp', 'ReduceSumSquare',
            'Constant', 'ConstantOfShape', 'Shape', 'Size',
            'Expand', 'Greater', 'Less', 'Equal', 'And', 'Or', 'Xor', 'Not',
            'Neg', 'Abs', 'Reciprocal', 'Floor', 'Ceil', 'Round',
            'Sqrt', 'Exp', 'Log', 'Pow', 'IsNaN', 'IsInf', 'Sign',
            'Min', 'Max', 'Mean', 'Sum', 'Prod'
        }
# Generated by default/object.tt
package Paws::SageMaker::InferenceExecutionConfig;
  use Moose;
  has Mode => (is => 'ro', isa => 'Str', required => 1);

1;

### main pod documentation begin ###

=head1 NAME

Paws::SageMaker::InferenceExecutionConfig

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::SageMaker::InferenceExecutionConfig object:

  $service_obj->Method(Att1 => { Mode => $value, ..., Mode => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::SageMaker::InferenceExecutionConfig object:

  $result = $service_obj->Method(...);
  $result->Att1->Mode

=head1 DESCRIPTION

Specifies details about how containers in a multi-container endpoint
are run.

=head1 ATTRIBUTES


=head2 B<REQUIRED> Mode => Str

How containers in a multi-container are run. The following values are
valid.

=over

=item *

C<SERIAL> - Containers run as a serial pipeline.

=item *

C<DIRECT> - Only the individual container that you specify is run.

=back




=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::SageMaker>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut


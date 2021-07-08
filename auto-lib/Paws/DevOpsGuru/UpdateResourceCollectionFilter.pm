# Generated by default/object.tt
package Paws::DevOpsGuru::UpdateResourceCollectionFilter;
  use Moose;
  has CloudFormation => (is => 'ro', isa => 'Paws::DevOpsGuru::UpdateCloudFormationCollectionFilter');

1;

### main pod documentation begin ###

=head1 NAME

Paws::DevOpsGuru::UpdateResourceCollectionFilter

=head1 USAGE

This class represents one of two things:

=head3 Arguments in a call to a service

Use the attributes of this class as arguments to methods. You shouldn't make instances of this class. 
Each attribute should be used as a named argument in the calls that expect this type of object.

As an example, if Att1 is expected to be a Paws::DevOpsGuru::UpdateResourceCollectionFilter object:

  $service_obj->Method(Att1 => { CloudFormation => $value, ..., CloudFormation => $value  });

=head3 Results returned from an API call

Use accessors for each attribute. If Att1 is expected to be an Paws::DevOpsGuru::UpdateResourceCollectionFilter object:

  $result = $service_obj->Method(...);
  $result->Att1->CloudFormation

=head1 DESCRIPTION

Contains information used to update a collection of AWS resources.

=head1 ATTRIBUTES


=head2 CloudFormation => L<Paws::DevOpsGuru::UpdateCloudFormationCollectionFilter>

An collection of AWS CloudFormation stacks. You can specify up to 500
AWS CloudFormation stacks.



=head1 SEE ALSO

This class forms part of L<Paws>, describing an object used in L<Paws::DevOpsGuru>

=head1 BUGS and CONTRIBUTIONS

The source code is located here: L<https://github.com/pplu/aws-sdk-perl>

Please report bugs to: L<https://github.com/pplu/aws-sdk-perl/issues>

=cut

